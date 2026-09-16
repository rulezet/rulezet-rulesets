rule TTP_XOR_QUAD_CurrentVersionRun_ffe3 {
  strings:
    $key_ffe3 = { ac 8c [2] 88 82 [2] a3 ae [2] 8d 8c [2] 99 97 [2] 96 8d [2] 88 90 [2] 8a 91 [2] 91 97 [2] 8d 90 [2] 91 bf }

  condition:
    any of them
}