rule TTP_XOR_WriteProcessMemory_835c {
  strings:
    $key_835c = { d4 2e [2] e6 0c [2] e0 39 [2] ce 39 [2] f1 25 }

  condition:
    any of them
}