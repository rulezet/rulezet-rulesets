rule TTP_XOR_WriteProcessMemory_32dd {
  strings:
    $key_32dd = { 65 af [2] 57 8d [2] 51 b8 [2] 7f b8 [2] 40 a4 }

  condition:
    any of them
}