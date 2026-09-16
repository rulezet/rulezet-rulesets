rule TTP_XOR_WriteProcessMemory_475c {
  strings:
    $key_475c = { 10 2e [2] 22 0c [2] 24 39 [2] 0a 39 [2] 35 25 }

  condition:
    any of them
}