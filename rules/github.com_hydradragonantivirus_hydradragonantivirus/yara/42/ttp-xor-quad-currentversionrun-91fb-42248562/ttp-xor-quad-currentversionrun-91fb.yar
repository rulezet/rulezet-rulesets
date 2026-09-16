rule TTP_XOR_QUAD_CurrentVersionRun_91fb {
  strings:
    $key_91fb = { c2 94 [2] e6 9a [2] cd b6 [2] e3 94 [2] f7 8f [2] f8 95 [2] e6 88 [2] e4 89 [2] ff 8f [2] e3 88 [2] ff a7 }

  condition:
    any of them
}