import "math"
rule math_entropy_1 : info statistics {
	meta:
	        description = "Very low entropy - repeating 2 bytes"

	condition:
		math.entropy(0, filesize) >= 1 and
		math.entropy(0, filesize) < 2
}