rule PSS_lnkproxy {
  meta:
    description = "PSS lnkproxy versions 4.x and 5.x"
    author      = "Geoffrey Alexander <geoff@citizenlab.ca>"
    date        = "2017-07-20"

  strings:
    $s1  = "COMMAND_LINE_BEGIN:" ascii
    $s2  = ":COMMAND_LINE_END:" ascii
    $s3  = "Could not execute process when no command is specified" ascii
    $s4  = "lnkproxy.db" ascii
    $s5  = "SPAWN_COMMAND_BEGIN:" ascii
    $s6  = ":SPAWN_COMMAND_END" ascii
    $s7  = "util::Deserializer::" ascii
    $s8  = "util::FileDeserializer::" ascii
    $s9  = "util::File::" ascii
    $s10 = "util::Process::" ascii
    $s11 = "util::System::" ascii

  condition:
    uint16(0) == 0x5a4d and 4 of ($s*)
}