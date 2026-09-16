rule TTP_XOR_QUAD_CurrentVersionRun_ccd1 {
  strings:
    $key_ccd1 = { 9f be [2] bb b0 [2] 90 9c [2] be be [2] aa a5 [2] a5 bf [2] bb a2 [2] b9 a3 [2] a2 a5 [2] be a2 [2] a2 8d }

  condition:
    any of them
}