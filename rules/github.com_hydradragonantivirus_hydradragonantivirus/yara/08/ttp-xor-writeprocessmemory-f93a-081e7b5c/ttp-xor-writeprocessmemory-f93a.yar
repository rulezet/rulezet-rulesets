rule TTP_XOR_WriteProcessMemory_f93a {
  strings:
    $key_f93a = { ae 48 [2] 9c 6a [2] 9a 5f [2] b4 5f [2] 8b 43 }

  condition:
    any of them
}