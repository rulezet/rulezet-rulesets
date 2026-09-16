rule TTP_XOR_QUAD_CurrentVersionRun_2e0c {
  strings:
    $key_2e0c = { 7d 63 [2] 59 6d [2] 72 41 [2] 5c 63 [2] 48 78 [2] 47 62 [2] 59 7f [2] 5b 7e [2] 40 78 [2] 5c 7f [2] 40 50 }

  condition:
    any of them
}