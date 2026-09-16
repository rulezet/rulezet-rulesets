import "math"
rule math_entropy_close_8 : info statistics {
	meta:
	        description = "Very high entropy - random stream, packed data or encryption"

	condition:
		math.entropy(0, filesize) >= 7.5
}