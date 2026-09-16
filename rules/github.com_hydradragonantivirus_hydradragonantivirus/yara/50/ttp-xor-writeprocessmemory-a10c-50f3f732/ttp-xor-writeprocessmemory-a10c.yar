rule TTP_XOR_WriteProcessMemory_a10c {
  strings:
    $key_a10c = { f6 7e [2] c4 5c [2] c2 69 [2] ec 69 [2] d3 75 }

  condition:
    any of them
}