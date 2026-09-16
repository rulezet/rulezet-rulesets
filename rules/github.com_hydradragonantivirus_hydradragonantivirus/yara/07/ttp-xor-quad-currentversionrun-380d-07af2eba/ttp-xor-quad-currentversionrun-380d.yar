rule TTP_XOR_QUAD_CurrentVersionRun_380d {
  strings:
    $key_380d = { 6b 62 [2] 4f 6c [2] 64 40 [2] 4a 62 [2] 5e 79 [2] 51 63 [2] 4f 7e [2] 4d 7f [2] 56 79 [2] 4a 7e [2] 56 51 }

  condition:
    any of them
}