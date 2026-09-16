rule TTP_XOR_WriteProcessMemory_695d {
  strings:
    $key_695d = { 3e 2f [2] 0c 0d [2] 0a 38 [2] 24 38 [2] 1b 24 }

  condition:
    any of them
}