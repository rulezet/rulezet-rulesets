rule TTP_XOR_QUAD_CurrentVersionRun_6cfe {
  strings:
    $key_6cfe = { 3f 91 [2] 1b 9f [2] 30 b3 [2] 1e 91 [2] 0a 8a [2] 05 90 [2] 1b 8d [2] 19 8c [2] 02 8a [2] 1e 8d [2] 02 a2 }

  condition:
    any of them
}