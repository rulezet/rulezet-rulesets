rule TTP_XOR_WriteProcessMemory_ab71 {
  strings:
    $key_ab71 = { fc 03 [2] ce 21 [2] c8 14 [2] e6 14 [2] d9 08 }

  condition:
    any of them
}