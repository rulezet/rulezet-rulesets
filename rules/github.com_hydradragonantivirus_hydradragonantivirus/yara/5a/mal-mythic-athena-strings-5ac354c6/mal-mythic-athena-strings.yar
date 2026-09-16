rule MAL_Mythic_Athena_strings {
  meta:
    description   = "Matches strings found in samples of the Athena agent used by the open-source Mythic framework."
    last_modified = "2024-02-08"
    author        = "@petermstewart"
    DaysofYara    = "39/100"
    sha256        = "8075738035ac361d50db2c2112a539acc3f1ad4d4ed5f971b2e18c687fc029da"
    sha256        = "ce66c7487e56722f34e5fd0fea167f9c562a0bbb0d13128b0313e4d3eabff697"
    ref           = "https://github.com/MythicAgents/athena"

  strings:
    $a   = "Athena"
    $b1  = "\"Athena.Commands\":"
    $b2  = "\"Athena.Forwarders.SMB\":"
    $c1  = "\"cat\":"
    $c2  = "\"drives\":"
    $c3  = "\"get-clipboard\":"
    $c4  = "\"get-localgroup\":"
    $c5  = "\"get-sessions\":"
    $c6  = "\"get-shares\":"
    $c7  = "\"hostname\":"
    $c8  = "\"ifconfig\":"
    $c9  = "\"ls\":"
    $c10 = "\"mkdir\":"
    $c11 = "\"mv\":"
    $c12 = "\"ps\":"
    $c13 = "\"pwd\":"
    $c14 = "\"rm\":"
    $c15 = "\"shell\":"
    $c16 = "\"shellcode\":"
    $c17 = "\"whoami\":"

  condition:
    uint16(0) == 0x5a4d and
    #a > 100 and
    all of ($b*) and
    8 of ($c*)
}