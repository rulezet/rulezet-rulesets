rule TTP_XOR_QUAD_CurrentVersionRun_0e0c {
  strings:
    $key_0e0c = { 5d 63 [2] 79 6d [2] 52 41 [2] 7c 63 [2] 68 78 [2] 67 62 [2] 79 7f [2] 7b 7e [2] 60 78 [2] 7c 7f [2] 60 50 }

  condition:
    any of them
}