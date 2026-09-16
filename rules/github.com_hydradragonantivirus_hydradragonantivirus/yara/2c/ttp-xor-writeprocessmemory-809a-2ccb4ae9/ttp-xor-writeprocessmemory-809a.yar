rule TTP_XOR_WriteProcessMemory_809a {
  strings:
    $key_809a = { d7 e8 [2] e5 ca [2] e3 ff [2] cd ff [2] f2 e3 }

  condition:
    any of them
}