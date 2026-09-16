import "pe"
rule _UPX_v0896__v102__v105__v122_DLL__Laszlo__Markus_ {
  meta:
    description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 DLL -> Laszlo & Markus"

  strings:
    $0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

  condition:
    $0 at pe.entry_point
}