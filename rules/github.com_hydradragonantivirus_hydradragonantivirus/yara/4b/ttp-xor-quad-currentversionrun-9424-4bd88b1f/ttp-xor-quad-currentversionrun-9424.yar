rule TTP_XOR_QUAD_CurrentVersionRun_9424 {
  strings:
    $key_9424 = { c7 4b [2] e3 45 [2] c8 69 [2] e6 4b [2] f2 50 [2] fd 4a [2] e3 57 [2] e1 56 [2] fa 50 [2] e6 57 [2] fa 78 }

  condition:
    any of them
}