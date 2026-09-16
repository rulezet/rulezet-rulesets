rule TTP_XOR_WriteProcessMemory_aecf {
  strings:
    $key_aecf = { f9 bd [2] cb 9f [2] cd aa [2] e3 aa [2] dc b6 }

  condition:
    any of them
}