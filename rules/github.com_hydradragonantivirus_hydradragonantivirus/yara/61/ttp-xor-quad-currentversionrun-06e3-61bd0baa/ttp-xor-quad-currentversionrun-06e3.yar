rule TTP_XOR_QUAD_CurrentVersionRun_06e3 {
  strings:
    $key_06e3 = { 55 8c [2] 71 82 [2] 5a ae [2] 74 8c [2] 60 97 [2] 6f 8d [2] 71 90 [2] 73 91 [2] 68 97 [2] 74 90 [2] 68 bf }

  condition:
    any of them
}