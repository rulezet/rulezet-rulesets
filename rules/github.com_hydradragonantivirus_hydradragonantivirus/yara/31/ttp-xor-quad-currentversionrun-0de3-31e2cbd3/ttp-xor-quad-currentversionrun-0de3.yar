rule TTP_XOR_QUAD_CurrentVersionRun_0de3 {
  strings:
    $key_0de3 = { 5e 8c [2] 7a 82 [2] 51 ae [2] 7f 8c [2] 6b 97 [2] 64 8d [2] 7a 90 [2] 78 91 [2] 63 97 [2] 7f 90 [2] 63 bf }

  condition:
    any of them
}