rule PEiD_01776_PRO_MIDI_Music_file_ {
  meta:
    description = "[PRO-MIDI Music file]"
    ep_only     = "false"

  strings:
    $a = { 52 49 46 46 ?? ?? ?? ?? 52 4D 49 44 }

  condition:
    $a
}