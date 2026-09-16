rule TTP_XOR_QUAD_CurrentVersionRun_112e {
  strings:
    $key_112e = { 42 41 [2] 66 4f [2] 4d 63 [2] 63 41 [2] 77 5a [2] 78 40 [2] 66 5d [2] 64 5c [2] 7f 5a [2] 63 5d [2] 7f 72 }

  condition:
    any of them
}