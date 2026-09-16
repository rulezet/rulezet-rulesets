rule TTP_XOR_WriteProcessMemory_f93f {
  strings:
    $key_f93f = { ae 4d [2] 9c 6f [2] 9a 5a [2] b4 5a [2] 8b 46 }

  condition:
    any of them
}