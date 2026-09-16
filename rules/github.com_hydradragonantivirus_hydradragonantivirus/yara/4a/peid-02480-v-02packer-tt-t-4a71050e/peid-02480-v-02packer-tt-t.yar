rule PEiD_02480_v_02Packer____tt_t_ {
  meta:
    description = "[v.02Packer -> tt.t]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 36 FE FF FF C3 90 ?? 00 }

  condition:
    $a
}