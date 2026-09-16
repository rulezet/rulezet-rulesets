rule TTP_XOR_WriteProcessMemory_a88e {
  strings:
    $key_a88e = { ff fc [2] cd de [2] cb eb [2] e5 eb [2] da f7 }

  condition:
    any of them
}