rule TTP_XOR_WriteProcessMemory_a12c {
  strings:
    $key_a12c = { f6 5e [2] c4 7c [2] c2 49 [2] ec 49 [2] d3 55 }

  condition:
    any of them
}