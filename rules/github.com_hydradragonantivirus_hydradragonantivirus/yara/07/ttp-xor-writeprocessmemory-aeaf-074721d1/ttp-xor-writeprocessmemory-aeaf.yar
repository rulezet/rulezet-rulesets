rule TTP_XOR_WriteProcessMemory_aeaf {
  strings:
    $key_aeaf = { f9 dd [2] cb ff [2] cd ca [2] e3 ca [2] dc d6 }

  condition:
    any of them
}