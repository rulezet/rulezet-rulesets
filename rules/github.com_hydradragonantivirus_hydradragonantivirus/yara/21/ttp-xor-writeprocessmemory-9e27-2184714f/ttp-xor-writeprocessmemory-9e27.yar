rule TTP_XOR_WriteProcessMemory_9e27 {
  strings:
    $key_9e27 = { c9 55 [2] fb 77 [2] fd 42 [2] d3 42 [2] ec 5e }

  condition:
    any of them
}