rule NeedsAdminAccess: PECheck {
  meta:
    author      = "_pusher_"
    description = "AdminAccess Signature Check"
    date        = "2017-05"

  strings:
        $a0 = "requestedExecutionLevel" fullword ascii nocase
    $a1 = "level=\"requireAdministrator" fullword ascii nocase
    $a2 = "level=\"highestAvailable" fullword ascii nocase

  condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
    $a0 and ($a1 or $a2)
}