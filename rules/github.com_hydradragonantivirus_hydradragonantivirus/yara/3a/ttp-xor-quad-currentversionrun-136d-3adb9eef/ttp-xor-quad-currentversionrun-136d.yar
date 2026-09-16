rule TTP_XOR_QUAD_CurrentVersionRun_136d {
  strings:
    $key_136d = { 40 02 [2] 64 0c [2] 4f 20 [2] 61 02 [2] 75 19 [2] 7a 03 [2] 64 1e [2] 66 1f [2] 7d 19 [2] 61 1e [2] 7d 31 }

  condition:
    any of them
}