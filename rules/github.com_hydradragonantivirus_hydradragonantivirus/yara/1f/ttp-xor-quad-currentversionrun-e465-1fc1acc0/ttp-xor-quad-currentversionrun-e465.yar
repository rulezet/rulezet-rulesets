rule TTP_XOR_QUAD_CurrentVersionRun_e465 {
  strings:
    $key_e465 = { b7 0a [2] 93 04 [2] b8 28 [2] 96 0a [2] 82 11 [2] 8d 0b [2] 93 16 [2] 91 17 [2] 8a 11 [2] 96 16 [2] 8a 39 }

  condition:
    any of them
}