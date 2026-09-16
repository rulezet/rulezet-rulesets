rule TTP_XOR_WriteProcessMemory_9997 {
  strings:
    $key_9997 = { ce e5 [2] fc c7 [2] fa f2 [2] d4 f2 [2] eb ee }

  condition:
    any of them
}