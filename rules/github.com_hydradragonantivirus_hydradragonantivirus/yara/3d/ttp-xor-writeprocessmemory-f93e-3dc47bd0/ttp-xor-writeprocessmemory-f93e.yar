rule TTP_XOR_WriteProcessMemory_f93e {
  strings:
    $key_f93e = { ae 4c [2] 9c 6e [2] 9a 5b [2] b4 5b [2] 8b 47 }

  condition:
    any of them
}