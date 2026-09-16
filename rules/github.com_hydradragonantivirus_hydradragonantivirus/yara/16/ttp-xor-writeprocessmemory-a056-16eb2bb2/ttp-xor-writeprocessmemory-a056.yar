rule TTP_XOR_WriteProcessMemory_a056 {
  strings:
    $key_a056 = { f7 24 [2] c5 06 [2] c3 33 [2] ed 33 [2] d2 2f }

  condition:
    any of them
}