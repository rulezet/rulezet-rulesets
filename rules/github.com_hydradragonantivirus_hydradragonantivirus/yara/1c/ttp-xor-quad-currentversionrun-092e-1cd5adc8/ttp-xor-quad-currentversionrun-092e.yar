rule TTP_XOR_QUAD_CurrentVersionRun_092e {
  strings:
    $key_092e = { 5a 41 [2] 7e 4f [2] 55 63 [2] 7b 41 [2] 6f 5a [2] 60 40 [2] 7e 5d [2] 7c 5c [2] 67 5a [2] 7b 5d [2] 67 72 }

  condition:
    any of them
}