import "math"
rule math_entropy_7 : info statistics {
	meta:
	        description = "High entropy - probably random stream, packed data or encryption"

	condition:
		math.entropy(0, filesize) >= 7 and
		math.entropy(0, filesize) < 7.5
}