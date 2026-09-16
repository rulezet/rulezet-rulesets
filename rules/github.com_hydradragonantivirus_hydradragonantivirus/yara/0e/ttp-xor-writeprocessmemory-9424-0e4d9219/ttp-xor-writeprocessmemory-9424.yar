rule TTP_XOR_WriteProcessMemory_9424 {
  strings:
    $key_9424 = { c3 56 [2] f1 74 [2] f7 41 [2] d9 41 [2] e6 5d }

  condition:
    any of them
}