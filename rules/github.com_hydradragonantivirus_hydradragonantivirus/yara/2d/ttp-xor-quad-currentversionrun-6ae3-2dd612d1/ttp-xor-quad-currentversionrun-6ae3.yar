rule TTP_XOR_QUAD_CurrentVersionRun_6ae3 {
  strings:
    $key_6ae3 = { 39 8c [2] 1d 82 [2] 36 ae [2] 18 8c [2] 0c 97 [2] 03 8d [2] 1d 90 [2] 1f 91 [2] 04 97 [2] 18 90 [2] 04 bf }

  condition:
    any of them
}