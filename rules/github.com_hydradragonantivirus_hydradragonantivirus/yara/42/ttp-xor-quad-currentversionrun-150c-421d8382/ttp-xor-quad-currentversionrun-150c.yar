rule TTP_XOR_QUAD_CurrentVersionRun_150c {
  strings:
    $key_150c = { 46 63 [2] 62 6d [2] 49 41 [2] 67 63 [2] 73 78 [2] 7c 62 [2] 62 7f [2] 60 7e [2] 7b 78 [2] 67 7f [2] 7b 50 }

  condition:
    any of them
}