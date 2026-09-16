rule TTP_XOR_WriteProcessMemory_ec33 {
  strings:
    $key_ec33 = { bb 41 [2] 89 63 [2] 8f 56 [2] a1 56 [2] 9e 4a }

  condition:
    any of them
}