rule TTP_XOR_QUAD_CurrentVersionRun_3c0c {
  strings:
    $key_3c0c = { 6f 63 [2] 4b 6d [2] 60 41 [2] 4e 63 [2] 5a 78 [2] 55 62 [2] 4b 7f [2] 49 7e [2] 52 78 [2] 4e 7f [2] 52 50 }

  condition:
    any of them
}