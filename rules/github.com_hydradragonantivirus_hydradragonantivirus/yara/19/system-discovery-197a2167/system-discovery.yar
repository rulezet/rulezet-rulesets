rule System_Discovery {
  meta:
    mitre = "T1082 System Information Discovery"

  strings:
    $a = "sw_vers"
    $b = "spctl"
    $c = "test-devid-status"
    $d = "csrutil"
    $e = "df -m / |"
    $f = "__kCFSystemVersionProductNameKey"
    $g = "__kCFSystemVersionProductVersionKey"
    $A = "sw_vers" base64
    $B = "spctl" base64
    $C = "test-devid-status" base64
    $D = "csrutil" base64
    $E = "df -m / |" base64
    $F = "__kCFSystemVersionProductNameKey" base64
    $G = "__kCFSystemVersionProductVersionKey" base64

  condition:
    any of them
}