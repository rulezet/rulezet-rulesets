rule TTP_XOR_WriteProcessMemory_ee27 {
  strings:
    $key_ee27 = { b9 55 [2] 8b 77 [2] 8d 42 [2] a3 42 [2] 9c 5e }

  condition:
    any of them
}