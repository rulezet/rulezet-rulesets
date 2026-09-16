rule TTP_XOR_QUAD_CurrentVersionRun_502e {
  strings:
    $key_502e = { 03 41 [2] 27 4f [2] 0c 63 [2] 22 41 [2] 36 5a [2] 39 40 [2] 27 5d [2] 25 5c [2] 3e 5a [2] 22 5d [2] 3e 72 }

  condition:
    any of them
}