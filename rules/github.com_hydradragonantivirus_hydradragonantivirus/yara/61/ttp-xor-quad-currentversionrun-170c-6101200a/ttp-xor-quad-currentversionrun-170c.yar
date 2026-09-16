rule TTP_XOR_QUAD_CurrentVersionRun_170c {
  strings:
    $key_170c = { 44 63 [2] 60 6d [2] 4b 41 [2] 65 63 [2] 71 78 [2] 7e 62 [2] 60 7f [2] 62 7e [2] 79 78 [2] 65 7f [2] 79 50 }

  condition:
    any of them
}