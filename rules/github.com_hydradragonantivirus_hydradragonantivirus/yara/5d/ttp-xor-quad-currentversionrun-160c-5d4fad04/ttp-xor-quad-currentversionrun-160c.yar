rule TTP_XOR_QUAD_CurrentVersionRun_160c {
  strings:
    $key_160c = { 45 63 [2] 61 6d [2] 4a 41 [2] 64 63 [2] 70 78 [2] 7f 62 [2] 61 7f [2] 63 7e [2] 78 78 [2] 64 7f [2] 78 50 }

  condition:
    any of them
}