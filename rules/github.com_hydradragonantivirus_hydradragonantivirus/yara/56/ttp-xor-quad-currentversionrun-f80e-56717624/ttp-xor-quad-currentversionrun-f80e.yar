rule TTP_XOR_QUAD_CurrentVersionRun_f80e {
  strings:
    $key_f80e = { ab 61 [2] 8f 6f [2] a4 43 [2] 8a 61 [2] 9e 7a [2] 91 60 [2] 8f 7d [2] 8d 7c [2] 96 7a [2] 8a 7d [2] 96 52 }

  condition:
    any of them
}