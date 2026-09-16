rule TTP_XOR_WriteProcessMemory_9996 {
  strings:
    $key_9996 = { ce e4 [2] fc c6 [2] fa f3 [2] d4 f3 [2] eb ef }

  condition:
    any of them
}