rule TTP_XOR_WriteProcessMemory_9944 {
  strings:
    $key_9944 = { ce 36 [2] fc 14 [2] fa 21 [2] d4 21 [2] eb 3d }

  condition:
    any of them
}