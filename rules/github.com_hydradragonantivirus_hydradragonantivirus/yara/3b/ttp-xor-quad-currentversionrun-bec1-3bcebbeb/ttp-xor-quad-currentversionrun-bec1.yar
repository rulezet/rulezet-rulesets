rule TTP_XOR_QUAD_CurrentVersionRun_bec1 {
  strings:
    $key_bec1 = { ed ae [2] c9 a0 [2] e2 8c [2] cc ae [2] d8 b5 [2] d7 af [2] c9 b2 [2] cb b3 [2] d0 b5 [2] cc b2 [2] d0 9d }

  condition:
    any of them
}